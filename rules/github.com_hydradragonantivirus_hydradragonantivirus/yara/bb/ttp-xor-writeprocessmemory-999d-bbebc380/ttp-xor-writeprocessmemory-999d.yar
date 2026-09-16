rule TTP_XOR_WriteProcessMemory_999d {
  strings:
    $key_999d = { ce ef [2] fc cd [2] fa f8 [2] d4 f8 [2] eb e4 }

  condition:
    any of them
}