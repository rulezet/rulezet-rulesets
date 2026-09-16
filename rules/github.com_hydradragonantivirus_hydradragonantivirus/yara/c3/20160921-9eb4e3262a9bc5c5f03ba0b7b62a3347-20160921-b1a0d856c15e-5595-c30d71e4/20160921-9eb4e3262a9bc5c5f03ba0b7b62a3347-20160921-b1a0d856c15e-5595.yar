rule _20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347_20160921_b1a0d856c15e_5595 {
  meta:
    description = "datamaliciousorder - from files 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash2       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash3       = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"

  strings:
    $s1 = "})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(" ascii
    $s2 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s3 = "{return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})" ascii
    $s4 = "eturn \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s5 = "urn \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}