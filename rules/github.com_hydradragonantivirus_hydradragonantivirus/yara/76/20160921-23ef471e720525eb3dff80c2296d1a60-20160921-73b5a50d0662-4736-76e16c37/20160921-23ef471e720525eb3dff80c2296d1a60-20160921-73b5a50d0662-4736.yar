rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_73b5a50d0662_4736 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_73b5a50d06622b8411077815f2717627.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash3       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = "turn \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s2 = "00(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";" ascii
    $s3 = "0(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";" ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(fun" ascii
    $s5 = "f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"N" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}