rule TTP_XOR_QUAD_CurrentVersionRun_f802 {
  strings:
    $key_f802 = { ab 6d [2] 8f 63 [2] a4 4f [2] 8a 6d [2] 9e 76 [2] 91 6c [2] 8f 71 [2] 8d 70 [2] 96 76 [2] 8a 71 [2] 96 5e }

  condition:
    any of them
}