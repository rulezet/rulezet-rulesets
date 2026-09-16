rule _20160921_382a0f9b1ae693f8ade627fd2d6a8b52_20160921_54325d6949c5_4936 {
  meta:
    description = "datamaliciousorder - from files 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash2       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash3       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash4       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1 = "){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"DIa\";})" ascii
    $s2 = "00(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYs" ascii
    $s3 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"NYh\";})(),(funct" ascii
    $s4 = "000(){return \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv" ascii
    $s5 = " \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}