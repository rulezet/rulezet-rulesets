rule TTP_XOR_QUAD_CurrentVersionRun_12fe {
  strings:
    $key_12fe = { 41 91 [2] 65 9f [2] 4e b3 [2] 60 91 [2] 74 8a [2] 7b 90 [2] 65 8d [2] 67 8c [2] 7c 8a [2] 60 8d [2] 7c a2 }

  condition:
    any of them
}