rule TTP_XOR_QUAD_CurrentVersionRun_0afa {
  strings:
    $key_0afa = { 59 95 [2] 7d 9b [2] 56 b7 [2] 78 95 [2] 6c 8e [2] 63 94 [2] 7d 89 [2] 7f 88 [2] 64 8e [2] 78 89 [2] 64 a6 }

  condition:
    any of them
}