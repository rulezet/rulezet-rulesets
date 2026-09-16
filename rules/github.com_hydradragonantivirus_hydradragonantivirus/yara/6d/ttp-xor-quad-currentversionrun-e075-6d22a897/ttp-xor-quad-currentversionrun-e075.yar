rule TTP_XOR_QUAD_CurrentVersionRun_e075 {
  strings:
    $key_e075 = { b3 1a [2] 97 14 [2] bc 38 [2] 92 1a [2] 86 01 [2] 89 1b [2] 97 06 [2] 95 07 [2] 8e 01 [2] 92 06 [2] 8e 29 }

  condition:
    any of them
}