rule TTP_XOR_QUAD_CurrentVersionRun_24fe {
  strings:
    $key_24fe = { 77 91 [2] 53 9f [2] 78 b3 [2] 56 91 [2] 42 8a [2] 4d 90 [2] 53 8d [2] 51 8c [2] 4a 8a [2] 56 8d [2] 4a a2 }

  condition:
    any of them
}