rule TTP_XOR_QUAD_CurrentVersionRun_eae0 {
  strings:
    $key_eae0 = { b9 8f [2] 9d 81 [2] b6 ad [2] 98 8f [2] 8c 94 [2] 83 8e [2] 9d 93 [2] 9f 92 [2] 84 94 [2] 98 93 [2] 84 bc }

  condition:
    any of them
}