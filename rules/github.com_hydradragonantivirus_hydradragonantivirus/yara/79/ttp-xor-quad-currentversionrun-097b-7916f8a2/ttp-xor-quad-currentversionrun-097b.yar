rule TTP_XOR_QUAD_CurrentVersionRun_097b {
  strings:
    $key_097b = { 5a 14 [2] 7e 1a [2] 55 36 [2] 7b 14 [2] 6f 0f [2] 60 15 [2] 7e 08 [2] 7c 09 [2] 67 0f [2] 7b 08 [2] 67 27 }

  condition:
    any of them
}