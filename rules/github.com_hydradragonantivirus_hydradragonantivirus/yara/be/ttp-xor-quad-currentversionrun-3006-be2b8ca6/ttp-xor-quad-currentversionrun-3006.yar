rule TTP_XOR_QUAD_CurrentVersionRun_3006 {
  strings:
    $key_3006 = { 63 69 [2] 47 67 [2] 6c 4b [2] 42 69 [2] 56 72 [2] 59 68 [2] 47 75 [2] 45 74 [2] 5e 72 [2] 42 75 [2] 5e 5a }

  condition:
    any of them
}