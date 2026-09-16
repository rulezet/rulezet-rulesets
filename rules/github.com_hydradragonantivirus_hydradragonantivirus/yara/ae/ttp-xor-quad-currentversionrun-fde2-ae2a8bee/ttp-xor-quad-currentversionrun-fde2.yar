rule TTP_XOR_QUAD_CurrentVersionRun_fde2 {
  strings:
    $key_fde2 = { ae 8d [2] 8a 83 [2] a1 af [2] 8f 8d [2] 9b 96 [2] 94 8c [2] 8a 91 [2] 88 90 [2] 93 96 [2] 8f 91 [2] 93 be }

  condition:
    any of them
}