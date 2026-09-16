rule _20160921_2bac0af1f20f4cf23b85236dea7e2f73_20160921_52ab3697b827_3576 {
  meta:
    description = "datamaliciousorder - from files 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash2       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash3       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"

  strings:
    $s1 = "unction fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s2 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){re" ascii
    $s3 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"" ascii
    $s4 = "\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function f" ascii
    $s5 = " fuck(){return \"YQt\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s6 = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}