rule TTP_XOR_QUAD_CurrentVersionRun_cc3f {
  strings:
    $key_cc3f = { 9f 50 [2] bb 5e [2] 90 72 [2] be 50 [2] aa 4b [2] a5 51 [2] bb 4c [2] b9 4d [2] a2 4b [2] be 4c [2] a2 63 }

  condition:
    any of them
}