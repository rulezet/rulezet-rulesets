rule TTP_XOR_QUAD_CurrentVersionRun_0f3f {
  strings:
    $key_0f3f = { 5c 50 [2] 78 5e [2] 53 72 [2] 7d 50 [2] 69 4b [2] 66 51 [2] 78 4c [2] 7a 4d [2] 61 4b [2] 7d 4c [2] 61 63 }

  condition:
    any of them
}