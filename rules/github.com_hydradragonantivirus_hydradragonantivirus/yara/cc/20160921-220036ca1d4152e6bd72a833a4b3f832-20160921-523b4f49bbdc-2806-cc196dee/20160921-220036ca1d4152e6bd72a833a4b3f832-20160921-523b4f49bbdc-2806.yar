rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_523b4f49bbdc_2806 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash3       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash4       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash5       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash6       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1 = "(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Br\";})(),(function f000(){re" ascii
    $s2 = "r\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"YTp\";})(),(function" ascii
    $s3 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(function f00" ascii
    $s4 = "(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){re" ascii
    $s5 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Tn\";})(),(function f000" ascii
    $s6 = "turn \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(" ascii
    $s7 = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}