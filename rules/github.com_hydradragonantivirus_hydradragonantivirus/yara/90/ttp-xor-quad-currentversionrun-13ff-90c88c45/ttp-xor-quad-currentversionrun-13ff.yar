rule TTP_XOR_QUAD_CurrentVersionRun_13ff {
  strings:
    $key_13ff = { 40 90 [2] 64 9e [2] 4f b2 [2] 61 90 [2] 75 8b [2] 7a 91 [2] 64 8c [2] 66 8d [2] 7d 8b [2] 61 8c [2] 7d a3 }

  condition:
    any of them
}