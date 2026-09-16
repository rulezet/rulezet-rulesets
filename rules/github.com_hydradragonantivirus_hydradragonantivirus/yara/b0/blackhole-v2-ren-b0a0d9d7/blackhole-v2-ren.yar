rule BlackHole_v2_ren: PDF {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    ref     = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
    weight  = 3

  strings:
    $magic   = "%PDF"
    $content = "Index[5 1 7 1 9 4 23 4 50"

  condition:
    $magic at 0 and $content
}