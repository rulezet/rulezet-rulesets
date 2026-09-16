rule TTP_XOR_QUAD_CurrentVersionRun_03ff {
  strings:
    $key_03ff = { 50 90 [2] 74 9e [2] 5f b2 [2] 71 90 [2] 65 8b [2] 6a 91 [2] 74 8c [2] 76 8d [2] 6d 8b [2] 71 8c [2] 6d a3 }

  condition:
    any of them
}