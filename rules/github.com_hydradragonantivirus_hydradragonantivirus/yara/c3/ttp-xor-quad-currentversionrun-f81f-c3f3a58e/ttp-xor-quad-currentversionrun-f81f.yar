rule TTP_XOR_QUAD_CurrentVersionRun_f81f {
  strings:
    $key_f81f = { ab 70 [2] 8f 7e [2] a4 52 [2] 8a 70 [2] 9e 6b [2] 91 71 [2] 8f 6c [2] 8d 6d [2] 96 6b [2] 8a 6c [2] 96 43 }

  condition:
    any of them
}