rule TTP_XOR_QUAD_CurrentVersionRun_f806 {
  strings:
    $key_f806 = { ab 69 [2] 8f 67 [2] a4 4b [2] 8a 69 [2] 9e 72 [2] 91 68 [2] 8f 75 [2] 8d 74 [2] 96 72 [2] 8a 75 [2] 96 5a }

  condition:
    any of them
}