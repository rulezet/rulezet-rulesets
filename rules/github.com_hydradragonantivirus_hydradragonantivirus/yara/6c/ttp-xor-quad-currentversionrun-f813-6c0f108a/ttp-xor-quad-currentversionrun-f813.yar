rule TTP_XOR_QUAD_CurrentVersionRun_f813 {
  strings:
    $key_f813 = { ab 7c [2] 8f 72 [2] a4 5e [2] 8a 7c [2] 9e 67 [2] 91 7d [2] 8f 60 [2] 8d 61 [2] 96 67 [2] 8a 60 [2] 96 4f }

  condition:
    any of them
}