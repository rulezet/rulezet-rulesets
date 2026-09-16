rule TTP_XOR_QUAD_CurrentVersionRun_50ff {
  strings:
    $key_50ff = { 03 90 [2] 27 9e [2] 0c b2 [2] 22 90 [2] 36 8b [2] 39 91 [2] 27 8c [2] 25 8d [2] 3e 8b [2] 22 8c [2] 3e a3 }

  condition:
    any of them
}