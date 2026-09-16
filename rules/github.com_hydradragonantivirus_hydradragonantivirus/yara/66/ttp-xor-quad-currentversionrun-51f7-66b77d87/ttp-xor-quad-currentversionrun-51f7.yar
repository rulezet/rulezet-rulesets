rule TTP_XOR_QUAD_CurrentVersionRun_51f7 {
  strings:
    $key_51f7 = { 02 98 [2] 26 96 [2] 0d ba [2] 23 98 [2] 37 83 [2] 38 99 [2] 26 84 [2] 24 85 [2] 3f 83 [2] 23 84 [2] 3f ab }

  condition:
    any of them
}