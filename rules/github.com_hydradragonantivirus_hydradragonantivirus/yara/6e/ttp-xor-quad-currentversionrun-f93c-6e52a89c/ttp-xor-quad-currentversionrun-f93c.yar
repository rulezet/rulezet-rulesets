rule TTP_XOR_QUAD_CurrentVersionRun_f93c {
  strings:
    $key_f93c = { aa 53 [2] 8e 5d [2] a5 71 [2] 8b 53 [2] 9f 48 [2] 90 52 [2] 8e 4f [2] 8c 4e [2] 97 48 [2] 8b 4f [2] 97 60 }

  condition:
    any of them
}