rule TTP_XOR_QUAD_CurrentVersionRun_090f {
  strings:
    $key_090f = { 5a 60 [2] 7e 6e [2] 55 42 [2] 7b 60 [2] 6f 7b [2] 60 61 [2] 7e 7c [2] 7c 7d [2] 67 7b [2] 7b 7c [2] 67 53 }

  condition:
    any of them
}