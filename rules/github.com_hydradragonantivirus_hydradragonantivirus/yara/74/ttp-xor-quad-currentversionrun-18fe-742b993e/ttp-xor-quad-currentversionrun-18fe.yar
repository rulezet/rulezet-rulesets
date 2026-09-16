rule TTP_XOR_QUAD_CurrentVersionRun_18fe {
  strings:
    $key_18fe = { 4b 91 [2] 6f 9f [2] 44 b3 [2] 6a 91 [2] 7e 8a [2] 71 90 [2] 6f 8d [2] 6d 8c [2] 76 8a [2] 6a 8d [2] 76 a2 }

  condition:
    any of them
}