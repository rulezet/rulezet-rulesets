rule TTP_XOR_QUAD_CurrentVersionRun_09ff {
  strings:
    $key_09ff = { 5a 90 [2] 7e 9e [2] 55 b2 [2] 7b 90 [2] 6f 8b [2] 60 91 [2] 7e 8c [2] 7c 8d [2] 67 8b [2] 7b 8c [2] 67 a3 }

  condition:
    any of them
}