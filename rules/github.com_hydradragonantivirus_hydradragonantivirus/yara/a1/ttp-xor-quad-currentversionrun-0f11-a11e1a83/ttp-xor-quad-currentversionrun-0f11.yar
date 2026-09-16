rule TTP_XOR_QUAD_CurrentVersionRun_0f11 {
  strings:
    $key_0f11 = { 5c 7e [2] 78 70 [2] 53 5c [2] 7d 7e [2] 69 65 [2] 66 7f [2] 78 62 [2] 7a 63 [2] 61 65 [2] 7d 62 [2] 61 4d }

  condition:
    any of them
}