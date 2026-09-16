rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_da4ec6dae2ec_1953 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = "return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(" ascii
    $s2 = "(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Do\";})(),(function f000()" ascii
    $s3 = ";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f" ascii
    $s4 = "{return \"ZGq\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s5 = "})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f0" ascii
    $s6 = "n f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return " ascii
    $s7 = "ion f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return " ascii
    $s8 = " \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(func" ascii
    $s9 = "urn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}