rule TTP_XOR_QUAD_CurrentVersionRun_53ff {
  strings:
    $key_53ff = { 00 90 [2] 24 9e [2] 0f b2 [2] 21 90 [2] 35 8b [2] 3a 91 [2] 24 8c [2] 26 8d [2] 3d 8b [2] 21 8c [2] 3d a3 }

  condition:
    any of them
}