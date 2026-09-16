rule _20160921_ad0fbcfca87e48302530672c4ceab093_20160921_b1a0d856c15e_5630 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash2       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash3       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1 = "h\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function " ascii
    $s2 = "(function fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s3 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){retu" ascii
    $s4 = "){return \"PDf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s5 = "on fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}