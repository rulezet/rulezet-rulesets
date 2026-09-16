rule PEiD_01172_MPEG_movie_file_ {
  meta:
    description = "[MPEG movie file]"
    ep_only     = "false"

  strings:
    $a = { 00 00 01 BA 2F FF FD E6 C1 80 18 61 00 00 01 BB }

  condition:
    $a
}