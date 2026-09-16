rule _20160921_5f7be0b4d162caa40e1fc5a06f9f867a_20160921_7c37cf57d8ed_5290 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash2       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash3       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"
    hash4       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"

  strings:
    $s1 = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s2 = "on fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii
    $s3 = ";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fu" ascii
    $s4 = "eturn \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s5 = "turn \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}