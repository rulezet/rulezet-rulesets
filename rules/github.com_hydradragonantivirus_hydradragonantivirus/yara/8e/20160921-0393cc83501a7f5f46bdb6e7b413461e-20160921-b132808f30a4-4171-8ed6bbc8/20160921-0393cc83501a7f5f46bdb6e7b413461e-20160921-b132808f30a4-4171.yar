rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_b132808f30a4_4171 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash3       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash4       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1 = "function f000(){return \"Nv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){ret" ascii
    $s2 = "rn \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(fu" ascii
    $s3 = "unction f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){re" ascii
    $s4 = "(){return \"HJm\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";" ascii
    $s5 = "(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}