rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_4800 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash3       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = "urn \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})()," ascii
    $s2 = "n \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(func" ascii
    $s3 = "{return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(" ascii
    $s4 = "ion f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s5 = ";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}