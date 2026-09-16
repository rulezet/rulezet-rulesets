rule TTP_XOR_QUAD_CurrentVersionRun_7efe {
  strings:
    $key_7efe = { 2d 91 [2] 09 9f [2] 22 b3 [2] 0c 91 [2] 18 8a [2] 17 90 [2] 09 8d [2] 0b 8c [2] 10 8a [2] 0c 8d [2] 10 a2 }

  condition:
    any of them
}