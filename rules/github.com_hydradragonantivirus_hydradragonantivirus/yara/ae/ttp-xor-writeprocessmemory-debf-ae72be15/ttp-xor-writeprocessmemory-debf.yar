rule TTP_XOR_WriteProcessMemory_debf {
  strings:
    $key_debf = { 89 cd [2] bb ef [2] bd da [2] 93 da [2] ac c6 }

  condition:
    any of them
}