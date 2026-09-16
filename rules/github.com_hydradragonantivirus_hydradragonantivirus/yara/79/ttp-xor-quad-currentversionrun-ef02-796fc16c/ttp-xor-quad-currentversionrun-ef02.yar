rule TTP_XOR_QUAD_CurrentVersionRun_ef02 {
  strings:
    $key_ef02 = { bc 6d [2] 98 63 [2] b3 4f [2] 9d 6d [2] 89 76 [2] 86 6c [2] 98 71 [2] 9a 70 [2] 81 76 [2] 9d 71 [2] 81 5e }

  condition:
    any of them
}