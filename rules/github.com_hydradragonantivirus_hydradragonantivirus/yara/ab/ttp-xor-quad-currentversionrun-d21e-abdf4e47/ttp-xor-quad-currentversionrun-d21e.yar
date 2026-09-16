rule TTP_XOR_QUAD_CurrentVersionRun_d21e {
  strings:
    $key_d21e = { 81 71 [2] a5 7f [2] 8e 53 [2] a0 71 [2] b4 6a [2] bb 70 [2] a5 6d [2] a7 6c [2] bc 6a [2] a0 6d [2] bc 42 }

  condition:
    any of them
}