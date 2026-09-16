rule TTP_XOR_QUAD_CurrentVersionRun_23ff {
  strings:
    $key_23ff = { 70 90 [2] 54 9e [2] 7f b2 [2] 51 90 [2] 45 8b [2] 4a 91 [2] 54 8c [2] 56 8d [2] 4d 8b [2] 51 8c [2] 4d a3 }

  condition:
    any of them
}