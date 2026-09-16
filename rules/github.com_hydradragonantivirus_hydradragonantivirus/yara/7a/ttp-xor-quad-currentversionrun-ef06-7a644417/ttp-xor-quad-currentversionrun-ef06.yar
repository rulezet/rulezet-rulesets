rule TTP_XOR_QUAD_CurrentVersionRun_ef06 {
  strings:
    $key_ef06 = { bc 69 [2] 98 67 [2] b3 4b [2] 9d 69 [2] 89 72 [2] 86 68 [2] 98 75 [2] 9a 74 [2] 81 72 [2] 9d 75 [2] 81 5a }

  condition:
    any of them
}