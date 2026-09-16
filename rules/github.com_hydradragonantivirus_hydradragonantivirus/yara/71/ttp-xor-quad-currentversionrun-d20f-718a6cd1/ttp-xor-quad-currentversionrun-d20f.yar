rule TTP_XOR_QUAD_CurrentVersionRun_d20f {
  strings:
    $key_d20f = { 81 60 [2] a5 6e [2] 8e 42 [2] a0 60 [2] b4 7b [2] bb 61 [2] a5 7c [2] a7 7d [2] bc 7b [2] a0 7c [2] bc 53 }

  condition:
    any of them
}