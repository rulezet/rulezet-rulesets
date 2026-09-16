rule TTP_XOR_QUAD_CurrentVersionRun_0f3e {
  strings:
    $key_0f3e = { 5c 51 [2] 78 5f [2] 53 73 [2] 7d 51 [2] 69 4a [2] 66 50 [2] 78 4d [2] 7a 4c [2] 61 4a [2] 7d 4d [2] 61 62 }

  condition:
    any of them
}