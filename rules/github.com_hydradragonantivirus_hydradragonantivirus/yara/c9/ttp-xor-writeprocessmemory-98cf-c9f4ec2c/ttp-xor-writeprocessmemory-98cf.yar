rule TTP_XOR_WriteProcessMemory_98cf {
  strings:
    $key_98cf = { cf bd [2] fd 9f [2] fb aa [2] d5 aa [2] ea b6 }

  condition:
    any of them
}