rule TTP_XOR_QUAD_CurrentVersionRun_0efe {
  strings:
    $key_0efe = { 5d 91 [2] 79 9f [2] 52 b3 [2] 7c 91 [2] 68 8a [2] 67 90 [2] 79 8d [2] 7b 8c [2] 60 8a [2] 7c 8d [2] 60 a2 }

  condition:
    any of them
}