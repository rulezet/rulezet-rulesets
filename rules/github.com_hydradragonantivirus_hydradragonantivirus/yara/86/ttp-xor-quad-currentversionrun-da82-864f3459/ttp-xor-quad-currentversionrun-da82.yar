rule TTP_XOR_QUAD_CurrentVersionRun_da82 {
  strings:
    $key_da82 = { 89 ed [2] ad e3 [2] 86 cf [2] a8 ed [2] bc f6 [2] b3 ec [2] ad f1 [2] af f0 [2] b4 f6 [2] a8 f1 [2] b4 de }

  condition:
    any of them
}