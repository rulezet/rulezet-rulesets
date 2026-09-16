rule TTP_XOR_QUAD_CurrentVersionRun_34fe {
  strings:
    $key_34fe = { 67 91 [2] 43 9f [2] 68 b3 [2] 46 91 [2] 52 8a [2] 5d 90 [2] 43 8d [2] 41 8c [2] 5a 8a [2] 46 8d [2] 5a a2 }

  condition:
    any of them
}