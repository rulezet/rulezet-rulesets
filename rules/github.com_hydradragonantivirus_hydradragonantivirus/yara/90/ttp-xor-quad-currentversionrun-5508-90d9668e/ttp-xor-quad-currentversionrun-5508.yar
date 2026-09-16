rule TTP_XOR_QUAD_CurrentVersionRun_5508 {
  strings:
    $key_5508 = { 06 67 [2] 22 69 [2] 09 45 [2] 27 67 [2] 33 7c [2] 3c 66 [2] 22 7b [2] 20 7a [2] 3b 7c [2] 27 7b [2] 3b 54 }

  condition:
    any of them
}