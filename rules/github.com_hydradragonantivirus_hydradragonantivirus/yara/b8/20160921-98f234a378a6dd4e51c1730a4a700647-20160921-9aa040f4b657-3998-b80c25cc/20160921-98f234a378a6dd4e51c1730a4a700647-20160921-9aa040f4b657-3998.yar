rule _20160921_98f234a378a6dd4e51c1730a4a700647_20160921_9aa040f4b657_3998 {
  meta:
    description = "datamaliciousorder - from files 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash2       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"
    hash3       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = "function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){ret" ascii
    $s2 = " f000(){return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Vu" ascii
    $s3 = "(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";" ascii
    $s4 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(function f000(){retur" ascii
    $s5 = "Ts\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s6 = ",(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}