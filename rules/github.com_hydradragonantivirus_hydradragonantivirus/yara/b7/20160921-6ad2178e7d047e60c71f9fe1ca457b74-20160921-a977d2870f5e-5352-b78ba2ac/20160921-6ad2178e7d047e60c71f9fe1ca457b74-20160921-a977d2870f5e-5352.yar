rule _20160921_6ad2178e7d047e60c71f9fe1ca457b74_20160921_a977d2870f5e_5352 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash2       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash3       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"
    hash4       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1 = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZGq\";})(),(f" ascii
    $s2 = "Ii\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})(),(function" ascii
    $s3 = ")(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s4 = "turn \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s5 = "0(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}