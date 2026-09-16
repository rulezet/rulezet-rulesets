rule _20160921_382a0f9b1ae693f8ade627fd2d6a8b52_20160921_54325d6949c5_4942 {
  meta:
    description = "datamaliciousorder - from files 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash2       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash3       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash4       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = "on f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s2 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s3 = " f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj" ascii
    $s4 = "(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(" ascii
    $s5 = "on f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}